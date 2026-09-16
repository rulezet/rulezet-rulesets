rule Windows_Trojan_OtterCookie_3e1bceb3 {
    meta:
        author = "Elastic Security"
        id = "3e1bceb3-317f-4a02-a276-839cfd0d8410"
        fingerprint = "6eba2bf2ea5febcec6f2690f78cabee34fd7b211f63654aa6b83d1da5a2792a4"
        creation_date = "2026-07-13"
        last_modified = "2026-07-15"
        threat_name = "Windows.Trojan.OtterCookie"
        reference_sample = "95bb3d2abd08108f7ed9a61cc8493ab3259cabf1b5a21073c75d89dac8f61c49"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "|vmware|virtualbox|qemu|kvm|xen|parallels|bochs" ascii wide
        $b = "/api/service/process/" ascii wide
        $c = "npm install socket.io-client --save --no-warnings --no-save --no-progress --loglevel silent"
        $d = "messge" ascii wide
        $e = "whoIm" ascii wide
        $f = "/api/service/makelog" ascii wide
    condition:
        5 of them
}