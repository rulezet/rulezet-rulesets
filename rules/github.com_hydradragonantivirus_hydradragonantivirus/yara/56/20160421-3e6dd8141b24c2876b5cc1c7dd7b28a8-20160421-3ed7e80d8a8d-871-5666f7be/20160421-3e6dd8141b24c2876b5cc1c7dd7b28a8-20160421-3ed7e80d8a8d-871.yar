rule _20160421_3e6dd8141b24c2876b5cc1c7dd7b28a8_20160421_3ed7e80d8a8d_871 {
  meta:
    description = "datamaliciousorder - from files 20160421_3e6dd8141b24c2876b5cc1c7dd7b28a8.js, 20160421_3ed7e80d8a8dc605aec8af75d1697e92.js, 20160421_fd947780f5e7a6ea8f55848086580d1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52442bb33d6ece0a62cada72647d45ef41588b5a967024d26a7b387116f12f36"
    hash2       = "494dedcd68a9320f24fd348d0c9f4e14578df25190e6c015fd1524dd8cf4af6b"
    hash3       = "8ea22d3dcb9e28f5ecdd48dc4433fda0c26e0afa8e6c8fab04343c154b280c57"

  strings:
    $s1  = "bcn_widget = \"resetText\", folding = 2; v_stored_filename = \"wpview_media_sandbox_styles\", Navigating = \"admin_page_access_d" ascii
    $s2  = "get_posts = get_per_page = stripping = this;" fullword ascii
    $s3  = "choice = \"removedControl\", get_posts = \"might\";" fullword ascii
    $s4  = "bcn_widget = \"resetText\", folding = 2; v_stored_filename = \"wpview_media_sandbox_styles\", Navigating = \"admin_page_access_d" ascii
    $s5  = "stripping = \"Tijuana\";" fullword ascii
    $s6  = "canonical.type =  + depending;" fullword ascii
    $s7  = "overrideable = canonical;" fullword ascii
    $s8  = "function thoug$h()" fullword ascii
    $s9  = "depending = 1," fullword ascii
    $s10 = "this = \"ccc\";" fullword ascii
    $s11 = "var _autosave_field = 0, canonical = \"author_id\";" fullword ascii
    $s12 = "} catch (SYST) {" fullword ascii
    $s13 = "choice = canonical;" fullword ascii
    $s14 = "} catch (avoids) {" fullword ascii
    $s15 = "} catch (_wp_credits_build_object_link) {" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (8 of them)
    ) or (all of them)
}