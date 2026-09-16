rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_cb7b906c44a3_5467 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash3       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash4       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = ",(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s2 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(fun" ascii
    $s3 = "00(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s4 = "rn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(fu" ascii
    $s5 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}