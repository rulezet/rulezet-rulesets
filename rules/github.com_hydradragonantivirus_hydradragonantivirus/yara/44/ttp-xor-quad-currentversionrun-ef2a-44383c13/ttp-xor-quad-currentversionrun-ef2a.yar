rule TTP_XOR_QUAD_CurrentVersionRun_ef2a {
  strings:
    $key_ef2a = { bc 45 [2] 98 4b [2] b3 67 [2] 9d 45 [2] 89 5e [2] 86 44 [2] 98 59 [2] 9a 58 [2] 81 5e [2] 9d 59 [2] 81 76 }

  condition:
    any of them
}