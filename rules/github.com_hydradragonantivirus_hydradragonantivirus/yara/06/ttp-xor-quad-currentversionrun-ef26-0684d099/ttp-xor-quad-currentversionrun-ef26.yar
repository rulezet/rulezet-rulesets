rule TTP_XOR_QUAD_CurrentVersionRun_ef26 {
  strings:
    $key_ef26 = { bc 49 [2] 98 47 [2] b3 6b [2] 9d 49 [2] 89 52 [2] 86 48 [2] 98 55 [2] 9a 54 [2] 81 52 [2] 9d 55 [2] 81 7a }

  condition:
    any of them
}