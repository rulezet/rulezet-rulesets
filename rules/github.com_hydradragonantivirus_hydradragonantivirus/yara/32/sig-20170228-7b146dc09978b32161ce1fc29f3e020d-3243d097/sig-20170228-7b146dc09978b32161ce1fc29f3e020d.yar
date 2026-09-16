rule sig_20170228_7b146dc09978b32161ce1fc29f3e020d {
  meta:
    description = "datamaliciousorder - file 20170228_7b146dc09978b32161ce1fc29f3e020d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63719843814de32c89988042b0e7fb7bbf9e582d72847922de40d35466168689"

  strings:
    $x1  = "return [Number.NaN, Number.NaN, Number.NaN, \"cmd.exe /c \\\"powershell  $\"];" fullword ascii
    $s2  = "return [\"WScript.Shell\", Number.NaN];" fullword ascii
    $s3  = "return [Number.NaN, \"Scripting.FileSystemObjec\"];" fullword ascii
    $s4  = "return [Number.NaN, \"if(mist.GetBaseName('C:')\"];" fullword ascii
    $s5  = "return [Number.NaN, Number.NaN, Number.NaN, \"pa'; Invoke-Expression ($\"];" fullword ascii
    $s6  = "return [\"run\", Number.NaN, Number.NaN];" fullword ascii
    $s7  = "return [Number.NaN, \" === '' && typeof mist.Ge\", Number.NaN];" fullword ascii
    $s8  = "var ludwixu = function (fzircunco) {" fullword ascii
    $s9  = "//var mist = xkufynpy[2][uleszecb(1)[1]](yfaw(1)[1] + etxexiwv(1)[1]);" fullword ascii
    $s10 = "return [Number.NaN, \"N';$ehuxp='^://';$psynro=\", Number.NaN];" fullword ascii
    $s11 = "return [Number.NaN, Number.NaN, \"''';$czinxe='^nPo';$kihze\", Number.NaN];" fullword ascii
    $s12 = "return [\"ugtim+$urtaxc+$ejzub+$vru\", Number.NaN];" fullword ascii
    $s13 = "return [Number.NaN, Number.NaN, \"='^''ht';$wymja='^-Ex';$h\"];" fullword ascii
    $s14 = "return [Number.NaN, \"';$opcunmo='^tio';$ymtaqx\", Number.NaN];" fullword ascii
    $s15 = "var sraxir = function (irunlo) {" fullword ascii
    $s16 = "var uqenr = [Function, Number.NaN][0];" fullword ascii
    $s17 = "return [\"$lajuxs='^oce';$xuvnizr='\", Number.NaN];" fullword ascii
    $s18 = "return [Number.NaN, Number.NaN, \"z='^ath';$ixsew='^ss ';$o\"];" fullword ascii
    $s19 = "return [Number.NaN, \"ro+$etnotxa+$ymtaqx+$uxpo\", Number.NaN];" fullword ascii
    $s20 = "return [\"zez+$hsemsejd+$yduv+$zaze\", Number.NaN, Number.NaN];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}