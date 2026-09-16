import "math"
rule math_entropy_0 : info statistics {
	meta:
	        description = "Very low entropy - all zeroes or same bytes"

	condition:
		math.entropy(0, filesize) >= 0 and
		math.entropy(0, filesize) < 1
}