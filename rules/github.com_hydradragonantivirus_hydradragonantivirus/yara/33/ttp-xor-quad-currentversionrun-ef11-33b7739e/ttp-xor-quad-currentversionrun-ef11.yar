rule TTP_XOR_QUAD_CurrentVersionRun_ef11 {
  strings:
    $key_ef11 = { bc 7e [2] 98 70 [2] b3 5c [2] 9d 7e [2] 89 65 [2] 86 7f [2] 98 62 [2] 9a 63 [2] 81 65 [2] 9d 62 [2] 81 4d }

  condition:
    any of them
}