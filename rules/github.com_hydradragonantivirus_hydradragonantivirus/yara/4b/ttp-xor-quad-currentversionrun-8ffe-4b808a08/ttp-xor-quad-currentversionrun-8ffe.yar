rule TTP_XOR_QUAD_CurrentVersionRun_8ffe {
  strings:
    $key_8ffe = { dc 91 [2] f8 9f [2] d3 b3 [2] fd 91 [2] e9 8a [2] e6 90 [2] f8 8d [2] fa 8c [2] e1 8a [2] fd 8d [2] e1 a2 }

  condition:
    any of them
}