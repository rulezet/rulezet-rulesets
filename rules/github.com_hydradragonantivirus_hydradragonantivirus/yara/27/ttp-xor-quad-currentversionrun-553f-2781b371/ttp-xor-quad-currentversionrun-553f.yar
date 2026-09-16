rule TTP_XOR_QUAD_CurrentVersionRun_553f {
  strings:
    $key_553f = { 06 50 [2] 22 5e [2] 09 72 [2] 27 50 [2] 33 4b [2] 3c 51 [2] 22 4c [2] 20 4d [2] 3b 4b [2] 27 4c [2] 3b 63 }

  condition:
    any of them
}