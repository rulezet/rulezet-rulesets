rule TTP_XOR_QUAD_CurrentVersionRun_6b3f {
  strings:
    $key_6b3f = { 38 50 [2] 1c 5e [2] 37 72 [2] 19 50 [2] 0d 4b [2] 02 51 [2] 1c 4c [2] 1e 4d [2] 05 4b [2] 19 4c [2] 05 63 }

  condition:
    any of them
}