rule TTP_XOR_QUAD_CurrentVersionRun_3062 {
  strings:
    $key_3062 = { 63 0d [2] 47 03 [2] 6c 2f [2] 42 0d [2] 56 16 [2] 59 0c [2] 47 11 [2] 45 10 [2] 5e 16 [2] 42 11 [2] 5e 3e }

  condition:
    any of them
}