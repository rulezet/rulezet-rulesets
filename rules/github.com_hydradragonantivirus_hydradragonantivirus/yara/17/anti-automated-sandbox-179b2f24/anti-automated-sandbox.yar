rule Anti_Automated_Sandbox
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Check JoeSandbox, Anubis, Threat Expert, Sandboxie, Cwsandbox"
    	strings:
    				$joe1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
		$joe2 = "RegQueryValue"
		$joe3 = "55274-640-2673064-23950"

				$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue"
        $s1 = "76487-337-8429955-22614"
        $s2 = "76487-640-1457236-23837"

                $f1 = "dbghelp.dll" nocase

                $f2 = "SbieDLL.dll" nocase

                $var1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $var2 = "76487-644-3177037-23510"

    condition:
        any of ($joe*) or
        $p1 and $c1 and 1 of ($s*) or
        1 of ($f*) or
        all of ($var*)
}