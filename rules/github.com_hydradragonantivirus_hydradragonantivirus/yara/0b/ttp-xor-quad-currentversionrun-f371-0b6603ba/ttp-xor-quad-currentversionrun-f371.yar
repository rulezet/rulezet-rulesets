rule TTP_XOR_QUAD_CurrentVersionRun_f371 {
  strings:
    $key_f371 = { a0 1e [2] 84 10 [2] af 3c [2] 81 1e [2] 95 05 [2] 9a 1f [2] 84 02 [2] 86 03 [2] 9d 05 [2] 81 02 [2] 9d 2d }

  condition:
    any of them
}