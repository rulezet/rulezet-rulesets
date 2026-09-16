rule TTP_XOR_QUAD_CurrentVersionRun_ef22 {
  strings:
    $key_ef22 = { bc 4d [2] 98 43 [2] b3 6f [2] 9d 4d [2] 89 56 [2] 86 4c [2] 98 51 [2] 9a 50 [2] 81 56 [2] 9d 51 [2] 81 7e }

  condition:
    any of them
}