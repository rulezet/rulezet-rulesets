rule TTP_XOR_QUAD_CurrentVersionRun_323f {
  strings:
    $key_323f = { 61 50 [2] 45 5e [2] 6e 72 [2] 40 50 [2] 54 4b [2] 5b 51 [2] 45 4c [2] 47 4d [2] 5c 4b [2] 40 4c [2] 5c 63 }

  condition:
    any of them
}