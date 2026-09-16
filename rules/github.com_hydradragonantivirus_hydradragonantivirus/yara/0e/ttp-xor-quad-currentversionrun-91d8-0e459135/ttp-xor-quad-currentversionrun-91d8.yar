rule TTP_XOR_QUAD_CurrentVersionRun_91d8 {
  strings:
    $key_91d8 = { c2 b7 [2] e6 b9 [2] cd 95 [2] e3 b7 [2] f7 ac [2] f8 b6 [2] e6 ab [2] e4 aa [2] ff ac [2] e3 ab [2] ff 84 }

  condition:
    any of them
}