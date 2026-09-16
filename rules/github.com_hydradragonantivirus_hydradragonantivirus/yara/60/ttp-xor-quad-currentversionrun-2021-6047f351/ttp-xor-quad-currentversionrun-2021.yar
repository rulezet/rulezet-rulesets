rule TTP_XOR_QUAD_CurrentVersionRun_2021 {
  strings:
    $key_2021 = { 73 4e [2] 57 40 [2] 7c 6c [2] 52 4e [2] 46 55 [2] 49 4f [2] 57 52 [2] 55 53 [2] 4e 55 [2] 52 52 [2] 4e 7d }

  condition:
    any of them
}