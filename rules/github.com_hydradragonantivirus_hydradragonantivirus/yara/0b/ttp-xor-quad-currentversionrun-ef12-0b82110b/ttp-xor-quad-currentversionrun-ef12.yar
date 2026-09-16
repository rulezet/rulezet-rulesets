rule TTP_XOR_QUAD_CurrentVersionRun_ef12 {
  strings:
    $key_ef12 = { bc 7d [2] 98 73 [2] b3 5f [2] 9d 7d [2] 89 66 [2] 86 7c [2] 98 61 [2] 9a 60 [2] 81 66 [2] 9d 61 [2] 81 4e }

  condition:
    any of them
}