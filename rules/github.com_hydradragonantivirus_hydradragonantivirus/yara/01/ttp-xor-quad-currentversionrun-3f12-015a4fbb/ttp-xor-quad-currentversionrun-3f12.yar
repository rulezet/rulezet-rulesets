rule TTP_XOR_QUAD_CurrentVersionRun_3f12 {
  strings:
    $key_3f12 = { 6c 7d [2] 48 73 [2] 63 5f [2] 4d 7d [2] 59 66 [2] 56 7c [2] 48 61 [2] 4a 60 [2] 51 66 [2] 4d 61 [2] 51 4e }

  condition:
    any of them
}