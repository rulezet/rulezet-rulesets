rule TTP_XOR_QUAD_CurrentVersionRun_3021 {
  strings:
    $key_3021 = { 63 4e [2] 47 40 [2] 6c 6c [2] 42 4e [2] 56 55 [2] 59 4f [2] 47 52 [2] 45 53 [2] 5e 55 [2] 42 52 [2] 5e 7d }

  condition:
    any of them
}