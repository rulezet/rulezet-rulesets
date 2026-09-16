rule _20160921_a3beeaf5374452a126fde6e8bd845f1d_20160921_aed247f3d228_770 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash2       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash3       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash4       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"
    hash5       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = " \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s2  = "n\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3  = "00(){return \"KDh\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\"" ascii
    $s4  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(f" ascii
    $s5  = "turn \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s6  = "\"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(func" ascii
    $s7  = "\"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(funct" ascii
    $s8  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";}" ascii
    $s9  = "on f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "function f000(){return \"Br\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s11 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(fu" ascii
    $s12 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s13 = "),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii
    $s14 = "unction f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})(),(function f000(){ret" ascii
    $s15 = "ion f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii
    $s16 = "f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp" ascii
    $s17 = "){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})" ascii
    $s18 = "0(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";" ascii
    $s19 = "function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s20 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}