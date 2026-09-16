rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_19d073f9fafc_1022 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash3       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash4       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash5       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash6       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash7       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash8       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash9       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash10      = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash11      = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash12      = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash13      = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash14      = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash15      = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1  = "on f000(){return \"Vu\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "n \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s3  = "urn \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s4  = "(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s5  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s6  = "\"Br\";})(),(function f000(){return \"MOc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DAp\";})(),(func" ascii
    $s7  = "){return \"Br\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(" ascii
    $s8  = "){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(" ascii
    $s9  = "000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s10 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy" ascii
    $s11 = "eturn \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"PTi\";})()" ascii
    $s12 = "on f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s13 = "turn \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s14 = "(){return \"ZFe\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";}" ascii
    $s15 = "0(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s16 = "n \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s17 = "tion f000(){return \"IAa\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return" ascii
    $s18 = "})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}