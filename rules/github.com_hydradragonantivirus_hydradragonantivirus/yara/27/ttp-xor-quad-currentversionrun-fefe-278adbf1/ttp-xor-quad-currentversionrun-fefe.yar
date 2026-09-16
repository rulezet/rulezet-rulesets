rule TTP_XOR_QUAD_CurrentVersionRun_fefe {
  strings:
    $key_fefe = { ad 91 [2] 89 9f [2] a2 b3 [2] 8c 91 [2] 98 8a [2] 97 90 [2] 89 8d [2] 8b 8c [2] 90 8a [2] 8c 8d [2] 90 a2 }

  condition:
    any of them
}