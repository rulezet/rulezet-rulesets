rule sig_20160525_ee8d7898c48c0cdcf1d84a446e16ef8a {
  meta:
    description = "datamaliciousorder - file 20160525_ee8d7898c48c0cdcf1d84a446e16ef8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9ecddc0c9ebf943c659cce9a976eee67b30235bc2c8585a5f70badbe0f4645"

  strings:
    $s1  = "in(887), 2) + Math.pow(Math.cos(887), 2) - 1))-954)) FAojiAKXIlxvHxNK += Mm(xTmvKyQBcjOUmK);else if (VxBjBwncfIDAHTrXr == (123 +" ascii
    $s2  = "function cnVfPXoFG(YmdpACMFaydni) {var VHFNSncVLfMiTYZBtequvnwd = idostpgJkXICErXxWsmMwq.join(OpBfqAjhTEolIHSD[0]);var xTmvKyQBc" ascii
    $s3  = "function WBXQYwgPjO(WvgAZIYsSbqnKjop,CpCkLBbB){return WvgAZIYsSbqnKjop.charAt(CpCkLBbB);}" fullword ascii
    $s4  = "YmdpACMFaydni.length);return FAojiAKXIlxvHxNK;}" fullword ascii
    $s5  = "function cnVfPXoFG(YmdpACMFaydni) {var VHFNSncVLfMiTYZBtequvnwd = idostpgJkXICErXxWsmMwq.join(OpBfqAjhTEolIHSD[0]);var xTmvKyQBc" ascii
    $s6  = "function dnCvKHUFGTUtjXnUt(jIHQLUWNamzKdZRDXtXKK,DUxjDdcIVeexw,YOeBvQJDz){return String.fromCharCode(jIHQLUWNamzKdZRDXtXKK,DUxjD" ascii
    $s7  = "function dnCvKHUFGTUtjXnUt(jIHQLUWNamzKdZRDXtXKK,DUxjDdcIVeexw,YOeBvQJDz){return String.fromCharCode(jIHQLUWNamzKdZRDXtXKK,DUxjD" ascii
    $s8  = "vWZlnpHzzDRTfr);else FAojiAKXIlxvHxNK += dnCvKHUFGTUtjXnUt(xTmvKyQBcjOUmK, yBMvWZlnpHzzDRTfr, bDXexARzmN);} while (lgFewgcoCZ < " ascii
    $s9  = "function CDKWgEff(YzuxFhJpzSZfydQybsORgvG,umNzMzvNNK){return String.fromCharCode(YzuxFhJpzSZfydQybsORgvG,umNzMzvNNK);}" fullword ascii
    $s10 = "function mYhXmIUfn(DQidcCMTro,WkIPFb){return DQidcCMTro.indexOf(WkIPFb);}" fullword ascii
    $s11 = "function Mm(UVfNMHgBCd){return String.fromCharCode(UVfNMHgBCd);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}