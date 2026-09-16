rule PEiD_00885_hmimys_protect_0_1____hmimys_ {
  meta:
    description = "[hmimys protect 0.1 -> hmimys]"
    ep_only     = "false"

  strings:
    $a = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 }

  condition:
    $a
}