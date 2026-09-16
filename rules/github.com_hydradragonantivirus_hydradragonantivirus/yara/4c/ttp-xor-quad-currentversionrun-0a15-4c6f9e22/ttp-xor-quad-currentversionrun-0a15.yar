rule TTP_XOR_QUAD_CurrentVersionRun_0a15 {
  strings:
    $key_0a15 = { 59 7a [2] 7d 74 [2] 56 58 [2] 78 7a [2] 6c 61 [2] 63 7b [2] 7d 66 [2] 7f 67 [2] 64 61 [2] 78 66 [2] 64 49 }

  condition:
    any of them
}