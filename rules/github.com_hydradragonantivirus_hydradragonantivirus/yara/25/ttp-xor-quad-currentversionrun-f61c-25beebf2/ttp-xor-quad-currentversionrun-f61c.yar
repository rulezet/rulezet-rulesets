rule TTP_XOR_QUAD_CurrentVersionRun_f61c {
  strings:
    $key_f61c = { a5 73 [2] 81 7d [2] aa 51 [2] 84 73 [2] 90 68 [2] 9f 72 [2] 81 6f [2] 83 6e [2] 98 68 [2] 84 6f [2] 98 40 }

  condition:
    any of them
}