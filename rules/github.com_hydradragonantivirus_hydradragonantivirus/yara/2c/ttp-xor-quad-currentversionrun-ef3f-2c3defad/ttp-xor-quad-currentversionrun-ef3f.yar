rule TTP_XOR_QUAD_CurrentVersionRun_ef3f {
  strings:
    $key_ef3f = { bc 50 [2] 98 5e [2] b3 72 [2] 9d 50 [2] 89 4b [2] 86 51 [2] 98 4c [2] 9a 4d [2] 81 4b [2] 9d 4c [2] 81 63 }

  condition:
    any of them
}