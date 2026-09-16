rule sig_20160316_9f64c3314b329434dcaaa49d0c4b8bb7 {
  meta:
    description = "datamaliciousorder - file 20160316_9f64c3314b329434dcaaa49d0c4b8bb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cfad69b4f525d375a351524fed56994431748b3be72cd09f969b1cdc49f3c27"

  strings:
    $s1 = "while (JfTDolJkvu[Rsgrhw + PZpEfhiZiJz + aySYwavxpfR + SMW + mTxAXp] < 4 ) {WScript[IxRKZJtoTbK + CDml + GoSnSZIMasl](1000)};" fullword ascii
    $s2 = "qtarFS + sZtkqjYrA + MvPormktIdyRC + jbUdhIxoLVt + TKfRJcdRRk + urN + JPGEvkybe + gHKCYaGGpHAV + pgBXtlqVZsUWSAK, false);" fullword ascii
    $s3 = "function mFRKSzxvz(n){return cdwQqYaCt + nrEWzMGBClH + cgImDMyCPEEkZTP + QvmKgFBYR + LlpJfLkz + xPBHTQdnFT + kIzewExrmbv + XHTVZ" ascii
    $s4 = "JfTDolJkvu[SMGMjgMnfc + okQcOYwcKu + apZKmIcqDfpDlu](wKrBF + MinWk + TRZmOODZu, sIlNomKOl + UXofLC + oSRWjb + OPLIWTMAUUjaGx + B" ascii
    $s5 = "function UzFJxenNjiDmbJY(lsrtmQIYJlgEe){ggfkxl[SZJect + XSyAfDvyDTNiBv + wpISAeZiXEMGXom](lsrtmQIYJlgEe, 0, 0);}" fullword ascii
    $s6 = "function mFRKSzxvz(n){return cdwQqYaCt + nrEWzMGBClH + cgImDMyCPEEkZTP + QvmKgFBYR + LlpJfLkz + xPBHTQdnFT + kIzewExrmbv + XHTVZ" ascii
    $s7 = "var sQLjbp = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}