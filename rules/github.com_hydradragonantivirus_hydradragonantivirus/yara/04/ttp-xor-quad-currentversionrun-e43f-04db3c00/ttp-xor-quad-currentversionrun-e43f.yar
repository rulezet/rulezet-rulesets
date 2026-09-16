rule TTP_XOR_QUAD_CurrentVersionRun_e43f {
  strings:
    $key_e43f = { b7 50 [2] 93 5e [2] b8 72 [2] 96 50 [2] 82 4b [2] 8d 51 [2] 93 4c [2] 91 4d [2] 8a 4b [2] 96 4c [2] 8a 63 }

  condition:
    any of them
}