rule TTP_XOR_QUAD_CurrentVersionRun_b01f {
  strings:
    $key_b01f = { e3 70 [2] c7 7e [2] ec 52 [2] c2 70 [2] d6 6b [2] d9 71 [2] c7 6c [2] c5 6d [2] de 6b [2] c2 6c [2] de 43 }

  condition:
    any of them
}