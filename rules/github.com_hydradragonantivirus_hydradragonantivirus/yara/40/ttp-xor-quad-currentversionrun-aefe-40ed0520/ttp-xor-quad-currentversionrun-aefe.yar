rule TTP_XOR_QUAD_CurrentVersionRun_aefe {
  strings:
    $key_aefe = { fd 91 [2] d9 9f [2] f2 b3 [2] dc 91 [2] c8 8a [2] c7 90 [2] d9 8d [2] db 8c [2] c0 8a [2] dc 8d [2] c0 a2 }

  condition:
    any of them
}