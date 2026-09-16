rule TTP_XOR_QUAD_CurrentVersionRun_30f3 {
  strings:
    $key_30f3 = { 63 9c [2] 47 92 [2] 6c be [2] 42 9c [2] 56 87 [2] 59 9d [2] 47 80 [2] 45 81 [2] 5e 87 [2] 42 80 [2] 5e af }

  condition:
    any of them
}