rule TTP_XOR_QUAD_CurrentVersionRun_913f {
  strings:
    $key_913f = { c2 50 [2] e6 5e [2] cd 72 [2] e3 50 [2] f7 4b [2] f8 51 [2] e6 4c [2] e4 4d [2] ff 4b [2] e3 4c [2] ff 63 }

  condition:
    any of them
}