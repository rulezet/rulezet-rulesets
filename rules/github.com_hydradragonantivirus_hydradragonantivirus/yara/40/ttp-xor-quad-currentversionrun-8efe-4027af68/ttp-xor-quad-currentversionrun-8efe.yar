rule TTP_XOR_QUAD_CurrentVersionRun_8efe {
  strings:
    $key_8efe = { dd 91 [2] f9 9f [2] d2 b3 [2] fc 91 [2] e8 8a [2] e7 90 [2] f9 8d [2] fb 8c [2] e0 8a [2] fc 8d [2] e0 a2 }

  condition:
    any of them
}