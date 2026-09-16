rule _MPEG_Layer_IIIII_music_file_
{
	meta:
		description = "MPEG Layer II/III music file"
	strings:
		$0 = {FF F5}
		$1 = {FF F3}
		$2 = {FF F8}
		$3 = {FF FC}
		$4 = {FF F0}
		$5 = {FF F4}
		$6 = {FF FB}
		$7 = {FF F7}
		$8 = {FF F6}
		$9 = {FF F9}
		$10 = {FF FA}
		$11 = {FF F2}
		$12 = {FF F1}
		$13 = {FF E3}
		$14 = {FF FE}
		$15 = {FF FD}
	condition:
		$0 at entrypoint or $1 or $2 or $3 or $4 or $5 or $6 at entrypoint or $7 or $8 or $9 or $10 or $11 or $12 or $13 or $14 or $15
}