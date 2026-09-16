rule sig_20151210_22e05a2a76f1eaed3ab7bec4c509c2c5 {
  meta:
    description = "datamaliciousorder - file 20151210_22e05a2a76f1eaed3ab7bec4c509c2c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13bb4c4195404cbc1970660f5ffd3477b8ce1c1461ae29619a2d335bbddbfa84"

  strings:
    $s1  = "function zyyFLBH(pmpObbCnzYKHeeUyPMTOccwJVAgzrQXAJFtC) {return !isNaN(parseFloat(pmpObbCnzYKHeeUyPMTOccwJVAgzrQXAJFtC)) && isFin" ascii
    $s2  = "function zyyFLBH(pmpObbCnzYKHeeUyPMTOccwJVAgzrQXAJFtC) {return !isNaN(parseFloat(pmpObbCnzYKHeeUyPMTOccwJVAgzrQXAJFtC)) && isFin" ascii
    $s3  = "function ZbmkVwWIIbUjGNVXE(CWMVo){CWRvrYzKeMl= '';for(ATWRvjxTxNW=(-235+235)/230; ATWRvjxTxNW < (454+308)/381; ATWRvjxTxNW++) {H" ascii
    $s4  = "ipdYbdXD[ATWRvjxTxNW]=(-242+242)/862; while(true) { if(HipdYbdXD[ATWRvjxTxNW] > CWMVo[ATWRvjxTxNW].length-(60+351)/411) { break;" ascii
    $s5  = "function SlgqlskGPRkfPvqbmuvfAFVwwXNzUzXmYAsPzxcNVmvALcnfEPfvel(NSvGdvLuZHTwI,gmnMOwYbxqmlCp){ return WrXcU[ZtPRa(NSvGdvLuZHTwI[" ascii
    $s6  = "function ZbmkVwWIIbUjGNVXE(CWMVo){CWRvrYzKeMl= '';for(ATWRvjxTxNW=(-235+235)/230; ATWRvjxTxNW < (454+308)/381; ATWRvjxTxNW++) {H" ascii
    $s7  = ";}} return CWRvrYzKeMl}" fullword ascii
    $s8  = "function VIWjPQPpmSL(rdvZbRvh,TtxKhT){return rdvZbRvh.split(TtxKhT)}" fullword ascii
    $s9  = "function SlgqlskGPRkfPvqbmuvfAFVwwXNzUzXmYAsPzxcNVmvALcnfEPfvel(NSvGdvLuZHTwI,gmnMOwYbxqmlCp){ return WrXcU[ZtPRa(NSvGdvLuZHTwI[" ascii
    $s10 = " YVrtJ;}function TRYKLlrGrrMOESQ(MIcwiPnqebcbxErLc){eval(MIcwiPnqebcbxErLc)}" fullword ascii
    $s11 = "function ZtPRa(qrRNcARXtOY,GtIcHGButLvrt,ZdDZRHTo){nbup=parseInt(qrRNcARXtOY,GtIcHGButLvrt);YVrtJ=nbup.toString(ZdDZRHTo);return" ascii
    $s12 = "function ZtPRa(qrRNcARXtOY,GtIcHGButLvrt,ZdDZRHTo){nbup=parseInt(qrRNcARXtOY,GtIcHGButLvrt);YVrtJ=nbup.toString(ZdDZRHTo);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}