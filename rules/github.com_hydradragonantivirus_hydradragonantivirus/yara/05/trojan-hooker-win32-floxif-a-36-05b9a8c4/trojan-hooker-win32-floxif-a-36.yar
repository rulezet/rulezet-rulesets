rule Trojan_Hooker_Win32_Floxif_A_36 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33474af88a6572f7586b17975a786dfe05f27ab2caea2de6c85b3695063c9a33"

  strings:
    $x1  = "for (var i = 0; i < tr.length; i++) tb.appendChild(tr[i]); if (!d) window.location.hash = ('sc=' + sc + '&so=' + so); };window.o" ascii
    $s2  = "<script>function srt(tb, sc, so, d) {var tr = Array.prototype.slice.call(tb.rows, 0),tr = tr.sort(function (a, b) { var c1 = a.c" ascii
    $s3  = "nload = function() {var tb = document.getElementById('tb');var m = /sc=([012]).so=(1|-1)/.exec(window.location.hash) || [0, 2, 1" ascii
    $s4  = "];var sc = m[1], so = m[2]; document.onclick = function(ev) { var c = ev.target.rel; if (c) {if (c == sc) so *= -1; srt(tb, c, s" ascii
    $s5  = "= b.cells[2].getAttribute('name'); return so * (t1 < 0 && t2 >= 0 ? -1 : t2 < 0 && t1 >= 0 ? 1 : n1 ? parseInt(n2) - parseInt(n1" ascii
    $s6  = "failed to open listener" fullword ascii
    $s7  = "failed to create connection" fullword ascii
    $s8  = "{\"get_versions\": true" fullword ascii
    $s9  = "%u:%u: Comment not allowed here" fullword ascii
    $s10 = "%p %d bytes (PLAIN) <- %d" fullword ascii
    $s11 = "o); sc = c; ev.preventDefault();}};srt(tb, sc, so, true);}</script>" fullword ascii
    $s12 = "Failed to create key BIO" fullword ascii
    $s13 = "read %d from ctl socket" fullword ascii
    $s14 = "Failed to open listener: %d" fullword ascii
    $s15 = "%u:%u: Unexpected EOF in block comment" fullword ascii
    $s16 = "%p %d bytes from %s:%d" fullword ascii
    $s17 = "%p: failed to accept: %d" fullword ascii
    $s18 = "select @ %ld num_ev=%d of %d, timeout=%d" fullword ascii
    $s19 = "%u:%u: Unexpected `%c` in comment opening sequence" fullword ascii
    $s20 = "%p conn from %s:%d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}