rule sig_20160514_839824bec3ef9e046f979d1c52f00efe {
  meta:
    description = "datamaliciousorder - file 20160514_839824bec3ef9e046f979d1c52f00efe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "415add0262a91d9f2c8f83bbdf0785be65e3aa4b0e7cbeacf4789cc6eae5bfa7"

  strings:
    $s1  = "while (xJazIuA < vVDTz - (7917 - 7915)) {" fullword ascii
    $s2  = "function kEY() {" fullword ascii
    $s3  = "return bNXCmDma;" fullword ascii
    $s4  = "return EQnAfW;" fullword ascii
    $s5  = "function fJbCVH() {" fullword ascii
    $s6  = "return bCxuuZUn[tLuYhbI];" fullword ascii
    $s7  = "return MPLKyocl;" fullword ascii
    $s8  = "function WkiE(iqMx) {" fullword ascii
    $s9  = "function mrSK() {" fullword ascii
    $s10 = "return wqhQTl;" fullword ascii
    $s11 = "return fhUV;" fullword ascii
    $s12 = "return bYubU;" fullword ascii
    $s13 = "return buKR;" fullword ascii
    $s14 = "XeiYg = true;" fullword ascii
    $s15 = "return pkXs;" fullword ascii
    $s16 = "function cLClo() {" fullword ascii
    $s17 = "return diQIIP;" fullword ascii
    $s18 = "return qBgKZP;" fullword ascii
    $s19 = "function IWSXSFG(INVuhU, jDtDTK) {" fullword ascii
    $s20 = "function GzXC() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}