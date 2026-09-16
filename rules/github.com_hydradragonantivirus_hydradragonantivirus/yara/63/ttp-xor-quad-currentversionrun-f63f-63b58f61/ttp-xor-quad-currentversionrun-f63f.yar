rule TTP_XOR_QUAD_CurrentVersionRun_f63f {
  strings:
    $key_f63f = { a5 50 [2] 81 5e [2] aa 72 [2] 84 50 [2] 90 4b [2] 9f 51 [2] 81 4c [2] 83 4d [2] 98 4b [2] 84 4c [2] 98 63 }

  condition:
    any of them
}