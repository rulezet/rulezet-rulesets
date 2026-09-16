rule sig_20160315_783c2031b86c77b23ef76efe9062764e {
  meta:
    description = "datamaliciousorder - file 20160315_783c2031b86c77b23ef76efe9062764e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b3b40f692737f99862f2cfce31d43ed6fc1bb493707fc2487d04f589e34925b"

  strings:
    $s1 = "function qBurayuYWSGH(jvOfsmoLfU){WshShell[kExdJDkTPG + uPIeK](jvOfsmoLfU, 0, 0);}" fullword ascii
    $s2 = "while (kWJHBHAafO.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "oQliJHq + TmGSJMB + Rywl + wabiEdFdep + dXThLVb + DUBh + XrtxmzJpqZPCi + tlFZwu + ajUVfCOOOfMB + rLSTLONayh, false);" fullword ascii
    $s4 = "kWJHBHAafO[rrJWlVUD + oLwixYlan + poDSGdd](admKsXgCYF + EDkyEsyf, xZjqikzU + vuwelUUN + kzaAxAKICVnjW + lxPd + ZjbrIRzBX + uShAY" ascii
    $s5 = "var OsmNKl = new Date();" fullword ascii
    $s6 = "function zlxgkBd(n){return dhpRIFlf + bZSXKtLWyI + UrgPtFsIbFsgWEF + nBMcgZrNKzqAy + suzkWcXE + PiGCajmkXRjLJkZ + ANAiytAPOHFzWW" ascii
    $s7 = "function zlxgkBd(n){return dhpRIFlf + bZSXKtLWyI + UrgPtFsIbFsgWEF + nBMcgZrNKzqAy + suzkWcXE + PiGCajmkXRjLJkZ + ANAiytAPOHFzWW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}