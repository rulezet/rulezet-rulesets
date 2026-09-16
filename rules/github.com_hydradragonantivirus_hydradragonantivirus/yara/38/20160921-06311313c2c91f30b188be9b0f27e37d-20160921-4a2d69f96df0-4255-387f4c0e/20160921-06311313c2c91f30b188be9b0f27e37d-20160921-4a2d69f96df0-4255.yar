rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_4255 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash4       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash5       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash6       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "n f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2 = "(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"QDg\";" ascii
    $s3 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(" ascii
    $s4 = "nction f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}