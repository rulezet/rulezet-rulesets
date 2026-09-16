rule Windows_Trojan_AveMaria_e01305a0 {
    meta:
        author = "Elastic Security"
        id = "e01305a0-724e-420a-99af-38a3c6436095"
        fingerprint = "52acf71c9a53a56337722c43d9bba34957815b8c2c6fe52bea9b38e343dae803"
        creation_date = "2025-08-18"
        last_modified = "2025-09-19"
        threat_name = "Windows.Trojan.AveMaria"
        reference_sample = "21f1e24abcda47e08ba3e6bf19c0b2d9adb52b908f625c4a08f74ade5b863bf9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "SOFTWARE\\_rptls" wide fullword
        $b = "-w %ws -d C -f %s" fullword
        $c = "RDPClip" wide fullword
        $d = "ExplorerIdentifier" wide fullword
        $e = "WM_FIND" wide fullword
        $f = "WM_DISP" wide fullword
        $g = "MsgBox.exe" wide fullword
        $h = "Hey I'm Admin" wide fullword
        $i = "/n:%temp%\\ellocnak.xml" wide fullword
        $j = "CommandHandler::handleStartVncCommand() Start VNC on port : %d" wide fullword
    condition:
        7 of them
}