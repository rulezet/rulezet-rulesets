rule TTP_XOR_QUAD_CurrentVersionRun_dbd9 {
  strings:
    $key_dbd9 = { 88 b6 [2] ac b8 [2] 87 94 [2] a9 b6 [2] bd ad [2] b2 b7 [2] ac aa [2] ae ab [2] b5 ad [2] a9 aa [2] b5 85 }

  condition:
    any of them
}