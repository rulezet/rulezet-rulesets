rule TTP_XOR_QUAD_CurrentVersionRun_dcd8 {
  strings:
    $key_dcd8 = { 8f b7 [2] ab b9 [2] 80 95 [2] ae b7 [2] ba ac [2] b5 b6 [2] ab ab [2] a9 aa [2] b2 ac [2] ae ab [2] b2 84 }

  condition:
    any of them
}