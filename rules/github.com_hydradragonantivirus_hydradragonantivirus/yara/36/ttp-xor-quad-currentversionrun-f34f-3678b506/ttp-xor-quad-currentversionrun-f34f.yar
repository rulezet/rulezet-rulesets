rule TTP_XOR_QUAD_CurrentVersionRun_f34f {
  strings:
    $key_f34f = { a0 20 [2] 84 2e [2] af 02 [2] 81 20 [2] 95 3b [2] 9a 21 [2] 84 3c [2] 86 3d [2] 9d 3b [2] 81 3c [2] 9d 13 }

  condition:
    any of them
}