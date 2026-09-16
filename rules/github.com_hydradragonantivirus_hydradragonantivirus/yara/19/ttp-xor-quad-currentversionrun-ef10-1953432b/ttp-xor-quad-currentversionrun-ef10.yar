rule TTP_XOR_QUAD_CurrentVersionRun_ef10 {
  strings:
    $key_ef10 = { bc 7f [2] 98 71 [2] b3 5d [2] 9d 7f [2] 89 64 [2] 86 7e [2] 98 63 [2] 9a 62 [2] 81 64 [2] 9d 63 [2] 81 4c }

  condition:
    any of them
}