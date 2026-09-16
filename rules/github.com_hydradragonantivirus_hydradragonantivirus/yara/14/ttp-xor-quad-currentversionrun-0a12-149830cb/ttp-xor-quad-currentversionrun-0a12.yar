rule TTP_XOR_QUAD_CurrentVersionRun_0a12 {
  strings:
    $key_0a12 = { 59 7d [2] 7d 73 [2] 56 5f [2] 78 7d [2] 6c 66 [2] 63 7c [2] 7d 61 [2] 7f 60 [2] 64 66 [2] 78 61 [2] 64 4e }

  condition:
    any of them
}