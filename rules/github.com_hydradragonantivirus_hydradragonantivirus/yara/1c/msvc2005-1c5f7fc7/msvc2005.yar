import "pe"
rule MSVC2005 {
  meta:
    author = "_pusher_"
    date   = "2016-08"
    linker = "8.00"

  condition:
    pe.rich_signature.version(40310) and (pe.rich_signature.version(21022) or pe.rich_signature.version(30729)) and pe.rich_signature.toolid(124) or
    pe.rich_signature.version(3094) and pe.rich_signature.version(50736) and pe.rich_signature.toolid(113) or
    pe.rich_signature.version(40310) and pe.rich_signature.version(4035) and pe.rich_signature.toolid(125)
        or (
      pe.rich_signature.version(50727)
    )
    and ((pe.linker_version.major == 8) and (pe.linker_version.minor == 0))
}