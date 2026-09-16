rule TTP_XOR_QUAD_CurrentVersionRun_0512 {
  strings:
    $key_0512 = { 56 7d [2] 72 73 [2] 59 5f [2] 77 7d [2] 63 66 [2] 6c 7c [2] 72 61 [2] 70 60 [2] 6b 66 [2] 77 61 [2] 6b 4e }

  condition:
    any of them
}