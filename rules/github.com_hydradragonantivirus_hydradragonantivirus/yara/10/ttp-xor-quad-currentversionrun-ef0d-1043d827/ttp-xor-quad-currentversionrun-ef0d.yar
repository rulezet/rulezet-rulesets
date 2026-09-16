rule TTP_XOR_QUAD_CurrentVersionRun_ef0d {
  strings:
    $key_ef0d = { bc 62 [2] 98 6c [2] b3 40 [2] 9d 62 [2] 89 79 [2] 86 63 [2] 98 7e [2] 9a 7f [2] 81 79 [2] 9d 7e [2] 81 51 }

  condition:
    any of them
}