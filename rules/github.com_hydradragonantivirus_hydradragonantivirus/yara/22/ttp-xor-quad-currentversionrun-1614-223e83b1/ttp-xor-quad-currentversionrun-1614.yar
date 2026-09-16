rule TTP_XOR_QUAD_CurrentVersionRun_1614 {
  strings:
    $key_1614 = { 45 7b [2] 61 75 [2] 4a 59 [2] 64 7b [2] 70 60 [2] 7f 7a [2] 61 67 [2] 63 66 [2] 78 60 [2] 64 67 [2] 78 48 }

  condition:
    any of them
}